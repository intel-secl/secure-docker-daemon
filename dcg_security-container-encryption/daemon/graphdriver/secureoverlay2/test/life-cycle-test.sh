#!/bin/bash

SCRIPT_DIR=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)

RGY_PORT=5000
RGY_NAME=secureoverlay2-test-registry
IMPORT=${SCRIPT_DIR}/../docs/make_secure.sh

run_docker() {
    args=( "$@" )
    # (>&2 echo "DEBUG: will run command 'docker ${args[@]}'")
    docker "${args[@]}"
}

die() {
    echo "ERROR (${1}): $?"
    exit 1
}

monitor() {
    echo -e "\n${*}"
    echo -n "date: "; date;
    # DEBUG: remove below once losetup leakage is fixed ...
    echo "losetup:"
    echo "- before (count=$(losetup --noheading --list | wc --lines)):"
    losetup
    echo "- clean:"
    losetup -D
    echo "- after (count=$(losetup --noheading --list | wc --lines)):"
    losetup
    echo ""
}

cleanup() {
    # - images
    run_docker rmi -f secureoverlay2-test-base 2> /dev/null
    run_docker rmi -f localhost:${RGY_PORT}/secureoverlay2-test-base 2> /dev/null
    run_docker rmi -f secureoverlay2-test-extend 2> /dev/null
    run_docker rmi -f secureoverlay2-test-import 2> /dev/null
    run_docker rmi -f secureoverlay2-test-import-extend 2> /dev/null

    # - registry
    run_docker stop ${RGY_NAME} 2> /dev/null
    run_docker rm ${RGY_NAME} 2> /dev/null
}
trap cleanup 0

run_test() {
    CONF_MODE=$1
    INT_MODE=$2
    SQUASH_MODE=$3

    monitor "\nRunning tests with confidentiality='${CONF_MODE}' / integrity='${INT_MODE}' / squash='${SQUASH_MODE}' ...\n--------------------------------------------------------------------------------------------------------------------------------"

    # - do sequence of

    # - create base image
    if [[ -z "${CONF_MODE}" || "${CONF_MODE}" = "--storage-opt RequiresConfidentiality=false" ]]; then
	SECOPTS="${CONF_MODE} ${INT_MODE} ${SQUASH_MODE}"
    else
	SECOPTS="${CONF_MODE} --storage-opt KeyType=key-type-string --storage-opt KeyHandle=baseKey --storage-opt KeyTypeOption=theBaseSecret ${INT_MODE} ${SQUASH_MODE}"
    fi

    monitor "before base build with options '${SECOPTS}'"

    run_docker build --no-cache -t secureoverlay2-test-base ${SECOPTS} image-base || die "base build"

    monitor "after base build"

    # - run
    base_run_out=$(run_docker run --rm secureoverlay2-test-base) || die "base run"
    base_run_out_expected="file '/test-dir/file1.txt' exists with content 'file1/base'; file '/test-dir/file2.txt' exists with content 'file2/base'; "
    [ "${base_run_out}" == "${base_run_out_expected}" ] || die "base run did not produce ``${base_run_out_expected}'' but ``${base_run_out}''"

    monitor "after base run"

    # - push to registry
    run_docker tag secureoverlay2-test-base localhost:${RGY_PORT}/secureoverlay2-test-base   || die "base tag for registry"
    run_docker push localhost:${RGY_PORT}/secureoverlay2-test-base   || die "base push"

    monitor "after base tag & push"

    # - delete
    run_docker rmi -f secureoverlay2-test-base   || die "base delete"
    run_docker rmi -f localhost:${RGY_PORT}/secureoverlay2-test-base   || die "base delete"
    # Note: this doesn't necessarily remove all layers if there are some left-over containers from runs.
    # Hence, we have to run all with option --rm 

    monitor "after base delete"

    # - pull & run from registry
    run_docker pull localhost:${RGY_PORT}/secureoverlay2-test-base   || die "base pull"
    run_docker tag localhost:${RGY_PORT}/secureoverlay2-test-base secureoverlay2-test-base || die "base tag for local"
    base_run_out=$(run_docker run --rm secureoverlay2-test-base) || die "base re-run"
    base_run_out_expected="file '/test-dir/file1.txt' exists with content 'file1/base'; file '/test-dir/file2.txt' exists with content 'file2/base'; "
    [ "${base_run_out}" == "${base_run_out_expected}" ] || die "base re-run did not produce ``${base_run_out_expected}'' but ``${base_run_out}''"

    monitor "after base pull, tag & run"

    # - extend: replace file1 with Val1' and remove file2
    if [[ -z "${CONF_MODE}" || "${CONF_MODE}" = "--storage-opt RequiresConfidentiality=false" ]]; then
	SECOPTS="${CONF_MODE} ${INT_MODE} ${SQUASH_MODE}"
    else
	SECOPTS="${CONF_MODE} --storage-opt KeyType=key-type-string --storage-opt KeyHandle=extendKey --storage-opt KeyTypeOption=theExtendSecret ${INT_MODE} ${SQUASH_MODE}"
    fi

    monitor "before extend build with options '${SECOPTS}'"

    run_docker build --no-cache -t secureoverlay2-test-extend ${SECOPTS} image-extend || die "extend build"

    monitor "after extend build"

    # - run
    extend_run_out=$(run_docker run --rm secureoverlay2-test-extend) || die "extend run"
    extend_run_out_expected="file '/test-dir/file1.txt' exists with content 'file1/extend'; file '/test-dir/file2.txt' does not exist; "
    [ "${extend_run_out}" == "${extend_run_out_expected}" ] || die "extend run did not produce ``${extend_run_out_expected}'' but ``${extend_run_out}''"

    monitor "after extend run"

    # - history/inspect
    #   TODO (eventually): cross-check for correct security options and alike

    # - test import / make_secure
    # - import (& run) ubuntu as ubuntu-import
    if [[ -z "${CONF_MODE}" || "${CONF_MODE}" = "--storage-opt RequiresConfidentiality=false" ]]; then
	SECOPTS="${CONF_MODE} ${INT_MODE} ${SQUASH_MODE}"
    else
	SECOPTS="${CONF_MODE} --storage-opt KeyType=key-type-string --storage-opt KeyHandle=importKey --storage-opt KeyTypeOption=theImportSecret ${INT_MODE} ${SQUASH_MODE}"
    fi

    monitor "before import with options '${SECOPTS}'"

    ${IMPORT} -s "${SECOPTS}" ubuntu secureoverlay2-test-import || die "import"

    monitor "after import and before import run"

    base_run_out=$(run_docker run --rm secureoverlay2-test-import /bin/echo "hello world") || die "import run"
    base_run_out_expected="hello world"
    [ "${base_run_out}" == "${base_run_out_expected}" ] || die "base run did not produce ``${base_run_out_expected}'' but ``${base_run_out}''"

    monitor "after import extend run"


    # - extend (& run) using image-base (--build-arg BASE_IMAGE=secureoverlay2-test-import)
    if [[ -z "${CONF_MODE}" || "${CONF_MODE}" = "--storage-opt RequiresConfidentiality=false" ]]; then
	SECOPTS="${CONF_MODE} ${INT_MODE} ${SQUASH_MODE}"
    else
	SECOPTS="${CONF_MODE} --storage-opt KeyType=key-type-string --storage-opt KeyHandle=importExtendKey --storage-opt KeyTypeOption=theImportExtendSecret ${INT_MODE} ${SQUASH_MODE}"
    fi

    monitor "before import extend build with options '${SECOPTS}'"

    run_docker build --no-cache -t secureoverlay2-test-import-extend --build-arg BASE_IMAGE=secureoverlay2-test-import ${SECOPTS} image-base || die "import extend build"

    monitor "after import extend build"

    base_run_out=$(run_docker run --rm secureoverlay2-test-import-extend) || die "import extend run"
    base_run_out_expected="file '/test-dir/file1.txt' exists with content 'file1/base'; file '/test-dir/file2.txt' exists with content 'file2/base'; "
    [ "${base_run_out}" == "${base_run_out_expected}" ] || die "base run did not produce ``${base_run_out_expected}'' but ``${base_run_out}''"

    monitor "after import extend run"


    # - cleanup
    run_docker rmi -f secureoverlay2-test-base || die "base delete"
    run_docker rmi -f localhost:${RGY_PORT}/secureoverlay2-test-base || die "base pull/re-run delete"
    run_docker rmi -f secureoverlay2-test-extend || die "extend delete"
    run_docker rmi -f secureoverlay2-test-import 2> /dev/null
    run_docker rmi -f secureoverlay2-test-import-extend 2> /dev/null

    monitor "after cleanup"
}



cd ${SCRIPT_DIR} || die ""

monitor "before setup"

# setup
# - registry
run_docker stop ${RGY_NAME};run_docker rm ${RGY_NAME} # ignore any errors, might not be running
run_docker run --name ${RGY_NAME} -p ${RGY_PORT}:${RGY_PORT} -d registry || die "registry start"
# - pre-load ubuntu image
run_docker pull ubuntu || die "failed to pull ubuntu base image"

monitor "after setup"

# Try various interesting storage option combinations
# note we add key handles later so we can do it build-dependent
for conf_mode in \
    "" \
    "--storage-opt RequiresConfidentiality=false" \
    "--storage-opt RequiresConfidentiality=true" \
; do {
    for int_mode in \
	"" \
	"--storage-opt RequiresIntegrity=true" \
    ; do {
        for squash_mode in \
            "" \
            "--squash" \
        ; do {
            run_test "${conf_mode}" "${int_mode}" "${squash_mode}"
        }; done
    }; done
}; done


monitor "\nAll tests successfully passed ..."

# overall cleanup
# -> handled by trap
